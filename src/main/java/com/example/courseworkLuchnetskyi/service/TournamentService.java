package com.example.courseworkLuchnetskyi.service;

import com.example.courseworkLuchnetskyi.dto.TournamentStandingDto;
import com.example.courseworkLuchnetskyi.dto.request.TournamentRequestDto;
import com.example.courseworkLuchnetskyi.dto.response.TournamentResponseDto;
import com.example.courseworkLuchnetskyi.dto.TournamentWinnerDto;


import java.util.List;

public interface TournamentService {
    TournamentResponseDto createTournament(TournamentRequestDto request);
    List<TournamentResponseDto> getAllTournaments();
    TournamentResponseDto updateTournament(Long id, TournamentRequestDto request);
    void deleteTournament(Long id);
    List<TournamentStandingDto> getTournamentStandings(Long tournamentId);
    List<TournamentWinnerDto> getTournamentWinners();
}
