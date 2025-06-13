package com.example.courseworkLuchnetskyi.controller;

import com.example.courseworkLuchnetskyi.dto.TournamentStandingDto;
import com.example.courseworkLuchnetskyi.dto.request.TournamentRequestDto;
import com.example.courseworkLuchnetskyi.dto.response.TournamentResponseDto;
import com.example.courseworkLuchnetskyi.service.TournamentService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import jakarta.validation.Valid;
import java.util.List;

@RestController
@RequestMapping("/api/tournaments")
@RequiredArgsConstructor
public class TournamentController {

    private final TournamentService tournamentService;

    @PostMapping
    public ResponseEntity<TournamentResponseDto> create(@RequestBody @Valid TournamentRequestDto request) {
        return new ResponseEntity<>(tournamentService.createTournament(request), HttpStatus.CREATED);
    }

    @GetMapping
    public List<TournamentResponseDto> getAll() {
        return tournamentService.getAllTournaments();
    }

    @PutMapping("/{id}")
    public TournamentResponseDto update(@PathVariable Long id, @RequestBody @Valid TournamentRequestDto request) {
        return tournamentService.updateTournament(id, request);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable Long id) {
        tournamentService.deleteTournament(id);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/{id}/standings")
    public ResponseEntity<List<TournamentStandingDto>> getStandings(@PathVariable Long id) {
        return ResponseEntity.ok(tournamentService.getTournamentStandings(id));
    }

    @GetMapping("/winners")
    public ResponseEntity<List<com.example.courseworkLuchnetskyi.dto.TournamentWinnerDto>> getWinners() {
        return ResponseEntity.ok(tournamentService.getTournamentWinners());
    }
}
