package com.example.courseworkLuchnetskyi.mapper;

import com.example.courseworkLuchnetskyi.dto.request.PlayerRequestDto;
import com.example.courseworkLuchnetskyi.dto.response.PlayerResponseDto;
import com.example.courseworkLuchnetskyi.dto.response.TeamResponseDto;
import com.example.courseworkLuchnetskyi.model.Player;
import com.example.courseworkLuchnetskyi.model.Team;
import java.time.LocalDate;
import javax.annotation.processing.Generated;
import org.springframework.stereotype.Component;

@Generated(
    value = "org.mapstruct.ap.MappingProcessor",
    date = "2025-06-12T13:09:28+0300",
    comments = "version: 1.5.5.Final, compiler: javac, environment: Java 17.0.13 (Amazon.com Inc.)"
)
@Component
public class PlayerMapperImpl implements PlayerMapper {

    @Override
    public Player toEntity(PlayerRequestDto dto) {
        if ( dto == null ) {
            return null;
        }

        Player player = new Player();

        player.setName( dto.name() );
        player.setBirthDate( dto.birthDate() );
        player.setPosition( dto.position() );

        return player;
    }

    @Override
    public PlayerResponseDto toDto(Player player) {
        if ( player == null ) {
            return null;
        }

        Long id = null;
        String name = null;
        LocalDate birthDate = null;
        String position = null;
        TeamResponseDto team = null;

        id = player.getId();
        name = player.getName();
        birthDate = player.getBirthDate();
        position = player.getPosition();
        team = teamToTeamResponseDto( player.getTeam() );

        PlayerResponseDto playerResponseDto = new PlayerResponseDto( id, name, birthDate, position, team );

        return playerResponseDto;
    }

    @Override
    public void updatePlayerFromDto(Player player, PlayerRequestDto dto) {
        if ( dto == null ) {
            return;
        }

        if ( dto.name() != null ) {
            player.setName( dto.name() );
        }
        if ( dto.birthDate() != null ) {
            player.setBirthDate( dto.birthDate() );
        }
        if ( dto.position() != null ) {
            player.setPosition( dto.position() );
        }
    }

    protected TeamResponseDto teamToTeamResponseDto(Team team) {
        if ( team == null ) {
            return null;
        }

        Long id = null;
        String name = null;
        String city = null;

        id = team.getId();
        name = team.getName();
        city = team.getCity();

        TeamResponseDto teamResponseDto = new TeamResponseDto( id, name, city );

        return teamResponseDto;
    }
}
