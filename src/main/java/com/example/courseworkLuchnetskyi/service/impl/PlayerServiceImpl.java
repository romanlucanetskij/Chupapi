package com.example.courseworkLuchnetskyi.service.impl;

import com.example.courseworkLuchnetskyi.dto.request.PlayerRequestDto;
import com.example.courseworkLuchnetskyi.dto.response.PlayerResponseDto;
import com.example.courseworkLuchnetskyi.exception.EntityNotFoundException;
import com.example.courseworkLuchnetskyi.dto.PlayerStatisticsDto;
import com.example.courseworkLuchnetskyi.dto.TeamAverageAgeDto;
import com.example.courseworkLuchnetskyi.mapper.PlayerMapper;
import com.example.courseworkLuchnetskyi.model.Player;
import com.example.courseworkLuchnetskyi.model.Team;
import com.example.courseworkLuchnetskyi.repository.PlayerRepository;
import com.example.courseworkLuchnetskyi.repository.TeamRepository;
import com.example.courseworkLuchnetskyi.service.PlayerService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.time.LocalDate;
import java.time.Period;

@Service
@RequiredArgsConstructor
public class PlayerServiceImpl implements PlayerService {

  private final PlayerRepository playerRepository;
  private final TeamRepository teamRepository;
  private final PlayerMapper playerMapper;

  @Override
  public PlayerResponseDto createPlayer(PlayerRequestDto dto) {
      Player player = playerMapper.toEntity(dto);
      player.setTeam(teamRepository.findById(dto.teamId())
              .orElseThrow(() -> new RuntimeException("Team not found")));
      return playerMapper.toDto(playerRepository.save(player));
  }

  @Override
  public List<PlayerResponseDto> getPlayersByTeam(Long teamId) {
      return playerRepository.findByTeamId(teamId).stream()
              .map(playerMapper::toDto)
              .toList();
  }

  @Override
  public PlayerResponseDto updatePlayer(Long playerId, PlayerRequestDto dto) {
      Player player = playerRepository.findById(playerId)
              .orElseThrow(() -> new RuntimeException("Player not found"));

      playerMapper.updatePlayerFromDto(player, dto);

      if (dto.teamId() != null) {
          player.setTeam(teamRepository.findById(dto.teamId())
                  .orElseThrow(() -> new RuntimeException("Team not found")));
      }

      return playerMapper.toDto(playerRepository.save(player));
  }

  @Override
  public void deletePlayer(Long playerId) {
      playerRepository.deleteById(playerId);
  }

  @Override
  public TeamAverageAgeDto getAverageAgeForTeam(Long teamId) {
    List<Player> players = playerRepository.findByTeamId(teamId);
    if (players.isEmpty()) {
      throw new RuntimeException("No players found for team with id: " + teamId);
    }

    double averageAge = players.stream()
      .mapToDouble(player -> calculateAge(player.getBirthDate()))
      .average()
      .orElse(0);
    TeamAverageAgeDto dto = new TeamAverageAgeDto();
    dto.setTeamId(teamId);
    dto.setTeamName(players.get(0).getTeam().getName());
    dto.setAverageAge(averageAge);
    return dto;
  }

  private double calculateAge(LocalDate birthDate) {
    return Period.between(birthDate, LocalDate.now()).getYears();
  }
  
  @Override
  public List<PlayerStatisticsDto> getPlayerStatisticsByTeam(Long teamId) {
      Team team = teamRepository.findById(teamId)
          .orElseThrow(() -> new EntityNotFoundException("Team not found"));

      List<Player> players = playerRepository.findByTeamId(teamId);

      return players.stream().map(player -> {
          PlayerStatisticsDto dto = new PlayerStatisticsDto();
          dto.setPlayerId(player.getId());
          dto.setPlayerName(player.getName());
          dto.setTeamName(team.getName());
          dto.setPosition(player.getPosition());
          dto.setMatchesPlayed(player.getMatchesPlayed());
          dto.setGoalsScored(player.getGoalsScored());
          return dto;
      }).toList();
  }

}
